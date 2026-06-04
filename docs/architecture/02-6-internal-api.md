# API surfaces — internal Rust API

The workspace has 12 crates: `kennel-policy`, `kennel-syscall`, `kennel-bpf`, `kennel-audit`, `kennel-config`, `kennel-spawn`, `kennel-netproxy`, `kennel-privhelper`, `kenneld`, `kennel-text`, `kennel-ssh-reorigin`, and `kennel-socks-connect`. The control protocol (CLI ↔ kenneld) lives in `kenneld::control`; the privhelper wire protocol in `kennel-privhelper::wire`; the `kennel` CLI is `kenneld/src/bin/kennel.rs`. `kennel-audit` is the unified audit writer (a first-class crate); `kennel-config` is the layered deployment/user configuration. Everything is blocking, thread-per-connection — there is no async runtime in the workspace. The authoritative per-crate API is the rustdoc (`cargo doc --no-deps`); this chapter is the review-boundary index.

## Stability commitment

**Unstable** per `02-0-overview.md`. Crate-to-crate APIs in the Project Kennel workspace are not commitments to external consumers. They are documented here as *review boundaries*: when a maintainer changes a crate's public surface, the change is visible at compile time across the workspace, and the documentation here helps reviewers understand what changed and why.

External parties may not write code that depends on these surfaces; consumers of the project use the stable surfaces (CLI, policy schema, audit JSONL) instead. If a consumer's use case is not served by any stable surface, the right response is to propose a stable surface, not to depend on an internal crate.

This chapter is a high-level index. The authoritative description of each crate's public API is the rustdoc generated from the crate's source (`cargo doc --no-deps`), with each `pub` item documented per CODING-STANDARDS.md §6.

---

## Crate index

The full workspace layout — directory structure, dependency graph, build feature flags — is in `03-crate-decomposition.md`. This section enumerates the crates and the *shape* of each public API surface.

### `kennel-policy`

**Purpose.** Parsing, template inheritance, signature verification, invariant validation for the policy TOML schema.

**Public surface.** (Exports from `lib.rs`; the resolved types are `EffectivePolicy` / `SettledPolicy` / `ResolvedChain` — there is no `Policy`, `RawPolicy`, `TemplateChain`, or `InstallConstants` type.)
- `SourcePolicy` (`source` module) — the parsed-but-unresolved source artefact (a template or leaf), with `parse(&[u8])` and `SourcePolicy::validate`.
- `ResolvedChain` / `resolve` / `resolve_verified` (`resolve` module) — chain-walk + include-merge to an effective `SourcePolicy`; `TemplateSource` is the artefact-fetch trait the resolver pulls parents/fragments through.
- `EffectivePolicy` — the flat, runtime-enforced rule sets (net/fs/exec/proc/cap/seccomp/lifecycle), the body of a settled policy (the translation target).
- `SettledPolicy` / `SignedSettledPolicy` — the flat, signed runtime artefact (`02-2-config-schema.md` §The settled policy). What `kennel-spawn` consumes. The per-kennel `SshRuntime` / `UnixRuntime` / `IdentityRuntime` / `AuditRuntime` / `EnvRuntime` service inputs ride alongside the `EffectivePolicy` in the settled document.
- `PolicyError` — every failure mode (parse, source-validation, translation, missing template, signature failure, lockfile mismatch, invariant violation, …).
- `compile` / `compile_leaf` / `seal_unsigned` / `Compiled` (`compile` module) — resolve → validate invariants → translate → produce the (un)signed settled document.
- `sign_settled(policy, key)` and `verify_settled(bytes, keys) -> Result<SettledPolicy, PolicyError>` — the latter is the runtime entry point: one signature verification, schema-version gate, framework-invariant re-assertion.
- `validate` / `InvariantViolation` (`invariant` module) — framework-invariant assertion over a settled policy.
- `KeySet` / `SigningKey` (`keys`), `Lockfile` / `LockEntry` (`lock`), `parse_leaf` / `LeafPolicy` (`leaf`).

**Depends on.** `serde`, `basic-toml` (both source and settled policies are TOML — no JSON), and the vetted `ed25519-compact` verifier. No Project Kennel crates — it is pure and I/O-free (callers read bytes from disk and pass them in).

**Depended on by.** The crates that read policy: `kennel-spawn` (consumes `SettledPolicy` via `verify_settled`) and `kenneld` (its `policy` module verifies; the `kennel compile` path in `src/bin/kennel.rs` drives `compile`/`sign_settled`). `kennel-netproxy` does **not** link it — the proxy parses its own per-kennel config.

**Notes.** This crate's public surface is the largest and most-consumed in the workspace. The `resolve`/`compile` path (heavy: parsing arbitrary templates, chain-walking, crypto) is exercised at compile time; the `verify_settled` path (light: one signature) is what runs on every spawn.

### `kennel-spawn`

**Purpose.** Translates a verified `SettledPolicy` into the actual setup sequence: framework-invariant re-assertion, per-instance substitution, namespaces, mounts, Landlock ruleset, seccomp BPF, capability drop, `PR_SET_NO_NEW_PRIVS`, environment construction, `execve`. It consumes settled policies, not source policies — it does not link the template/resolution machinery.

**Public surface.** (Free functions over a `Plan`, not a `Spawn`/`Workload` builder.)
- `Plan` (`plan` module) — the translated set of kernel-enforcement objects (bind mounts, the shim view, the proxy endpoint, namespaces, the Landlock/seccomp inputs). Built by `Plan::from_policy`. Re-exported alongside `BindMount`, `ProxyEndpoint`, `ShimView`.
- `RuntimeSubstitutions` — the per-instance values (`ctx`, `uid`, `kennel`, `home`, `namespace`, `tag`) the runtime fills into a settled policy's deferred placeholders.
- `substitute(policy, subst) -> Result<SettledPolicy, SpawnError>` — fill the deferred placeholders and refuse any that remain.
- `prepare(bytes, keys, subst) -> Result<Plan, SpawnError>` — the runtime entry point: `verify_settled` the bytes, substitute, translate into a `Plan`.
- `spawn(plan, command) -> Result<Child, SpawnError>` and `spawn_with_gid_map(plan, command, map_gids)` — apply the irreversible seal in the forked child immediately before `execve`; the `gid_map` variant runs the §7.2.8 privileged `gid_map` handshake on a servicer thread.
- `SpawnError` variants for every failure point, including `Policy` (verification), `UnsubstitutedPlaceholder` (boundary 13 in `04-trust-boundaries.md`), and `Syscall`.

**Depends on.** `kennel-policy` (for `SettledPolicy` and `verify_settled`), `kennel-syscall`, `kennel-bpf`. `#![forbid(unsafe_code)]` — every syscall routes through `kennel-syscall`/`kennel-bpf`. An optional `bwrap-compose` build-time feature delegates the namespace/mount phase to bubblewrap (see `03-crate-decomposition.md`).

**Depended on by.** `kenneld` — kenneld performs the spawn on the CLI's behalf (the CLI passes the workload's stdio over `SCM_RIGHTS` and kenneld runs the spawn sequence).

### `kennel-netproxy`

**Purpose.** SOCKS5/HTTP proxy enforcing the per-destination network allowlist. A binary crate (`main.rs`) with a library half (`lib.rs`) so the server, allowlist evaluator, and audit formatter are unit-testable without the network.

**Public surface.** The proxy reads its per-kennel TOML config (written by kenneld) at startup. The server lives in `src/server.rs`/`socks5.rs`/`http.rs`, the allowlist evaluator in `src/allow.rs`, and the JSONL audit formatter in `src/audit.rs` (one record per request; the server owns the sink — a per-kennel file wired by kenneld, or stderr). Blocking, one thread per connection.

**Depends on.** `kennel-audit` (the egress records go through the unified `Writer`). It does **not** link `kennel-policy`: the proxy parses its own per-kennel TOML config (`src/config.rs`) rather than the source/settled schema. No async runtime — the proxy is deliberately built without a `tokio`/`mio` tree (see `03-crate-decomposition.md`).

**Depended on by.** `kenneld` links the crate (it shares config types and invokes the binary per kennel).

### `kennel-bpf`

**Purpose.** BPF program loader. Owns the `.bpf.o` files and a hand-rolled `bpf(2)` loader over `libc`, using `object` only for ELF parsing — **not** libbpf-rs/libbpf-sys or aya (which would pull in a large C-vendoring or crate tree). The map definitions live in Rust (`KENNEL_MAPS`), mirroring `bpf/maps.h`; the programs compile against the kernel UAPI (no CO-RE), so the loader only resolves map relocations by symbol name.

**Public surface.** (There is no `BpfRuntime` handle, no `attach_to_cgroup`, and no `next_audit_event` — the surface is a loader plus a ringbuf reader.)
- `load_program` / `Loaded` (`loader` module) — load and relocate one compiled program object; `Loaded` holds the resulting program/map fds.
- `MapSpec` / `ProgramSpec` and the `KENNEL_MAPS` / `KENNEL_PROGRAMS` tables — the Rust descriptions of the maps and programs, mirroring `bpf/maps.h`.
- `RingBuffer` (`ringbuf` module) — the lock-free `mmap`'d audit-event drain (the reader that feeds kenneld; drops on a full buffer).
- `programs::object(name)` — the embedded compiled `.o` bytes, available only under the `embed-programs` feature.

**Depends on.** `object` (ELF parsing) and `libc` (the `bpf(2)` FFI; `kennel-bpf` is the second `unsafe` crate). It does **not** depend on `kennel-policy`; the egress map entries are built by `kennel-spawn::plan` and carried over the privhelper wire.

**Depended on by.** `kennel-privhelper` *optionally* (under `bpf-egress`, for the egress load/attach), `kenneld` (the ringbuf reader). `kennel-spawn` references it for the egress map-entry types; the actual cgroup attach is done by the privhelper, not in `kennel-spawn`.

**Notes.** Crate-level `#![allow(unsafe_code)]` for the `bpf(2)` FFI boundary (confined to `sys.rs`); reviewed under §4. ELF parsing is delegated to `object`.

### `kennel-privhelper`

**Purpose.** The privileged binary. Reads a fixed-layout request from stdin, validates it, performs one network/cgroup operation, writes a response to stdout, exits.

**Public surface (binary + library).** The wire format is fixed-size packed structs in the `wire` module (`src/wire.rs`), documented in `02-4-ipc.md` under "kenneld ↔ privhelper protocol". The crate has a library half exposing `wire`/`validate`; the rest is `pub(crate)` and tested in-crate.

**Depends on.** `kennel-syscall` (for the privileged syscalls — netlink address ops), and an **optional** `kennel-bpf` pulled in only under the `bpf-egress` feature (for the egress load/attach). Not `kennel-text` and not `serde`: the IPC is fixed-layout packed structs over stdin/stdout (`wire`, packed field-by-field), and the validation core is std-only — so the crate stays `#![forbid(unsafe_code)]`. A plain build links neither `kennel-bpf` nor clang.

**Depended on by.** `kenneld` links the crate's library half (`wire`/`validate`/`client`) to drive the helper; it also invokes the binary.

**Notes.** Compiled with `[profile.release] panic = "abort"`; `[profile.test] panic = "unwind"` per CODING-STANDARDS.md §8.5. `clippy::expect_used` is `deny` in this crate per §8.3.

### `kennel-syscall`

**Purpose.** One of the two crates permitted to contain `unsafe` blocks (the other is `kennel-bpf`). Wraps raw Linux syscalls, namespace operations, Landlock primitives, seccomp installation, and capability manipulation. (The `bpf(2)` FFI lives in `kennel-bpf`, not here.)

**Public surface.** A module per concern, each a safe wrapper over the raw syscalls: `landlock` (the `Ruleset` builder + `Scope`/`AccessFs`/`AccessNet`), `namespace` (the userns/mount/PID unshare and `establish_identity_userns`), `mount`, `seccomp`, `process` (`set_no_new_privs`), `path` (canonical-path resolution), `netlink` (the privhelper's address ops), `scm` (`SCM_RIGHTS`), `signal`, `spawn` (`spawn_sealed`, `fork_into_pid1`), `handshake`, `listenfd`, `unistd`, and — for `kennel-audit` — `journal` (journald FFI) and `random` (UUIDv7 randomness).

**Depends on.** `nix`, `libc`. (`kennel-bpf` builds its `bpf(2)` FFI on `libc` + `object` directly, not on a `-sys` crate.)

**Depended on by.** `kennel-spawn`, `kennel-privhelper`, `kenneld`, and `kennel-audit` (the latter only under `audit-journald`, for the journald FFI and the UUIDv7 randomness). Notably **not** `kennel-policy`, which is pure and links no Project Kennel crate.

**Notes.** Crate-level `#![allow(unsafe_code)]`; every `unsafe` block follows the comment template in §4. The crate is sized to be reviewable in one sitting — target ceiling 1500 lines of Rust.

### `kennel-audit`

**Purpose.** The unified audit writer (`#![forbid(unsafe_code)]`): the seam between audit *sources* (the BPF drain, the netproxy, the privhelper, the spawn wrapper, kenneld) and audit *sinks* (file, stdout, syslog, and — feature `audit-journald` — journald). A source builds an `Event`; the `Writer` stamps the envelope, runs one `kennel-text` sanitisation pass, applies the per-class `Level`, and fans the rendered record out to every configured `Sink`.

**Public surface.**
- `Event` / `Level` / `Outcome` / `Resource` / `Source` / `Value` (`event` module) — the event schema; the durable contract is `02-3-audit-schema.md`.
- `Writer` / `WriterContext` / `Levels` / `Sink` / `SinkError` (`writer` module) — the writer, its build-time context, and the sink trait; `MAX_EVENT_BYTES` / `SCHEMA_VERSION` constants.
- `FileSink` / `StdoutSink` / `SyslogSink` (`sinks`), `TimeoutSink` (`timeout`), and `JournaldSink` under `audit-journald`.
- `SinkConfig` / `SinkKind` / `facility_code` / `hostname` (`build`), `Record` / `Rendered` (`render`), `format_uuid_v7`, `Clock` / `SystemClock` / `format_rfc3339_micros` (`time`).

**Depends on.** `kennel-text` (the single sanitisation pass). The journald FFI and the UUIDv7 randomness — the only parts needing `unsafe`/FFI — live in `kennel-syscall` (`journal`, `random`), not here.

**Depended on by.** `kenneld` (builds the `Writer` from the settled `AuditRuntime`, emits lifecycle events) and `kennel-netproxy` (builds its own `Writer` from the per-kennel proxy config, emits each `net.egress` record). Not yet routed through the writer: the BPF ringbuf events — a roadmap remnant; see `03-crate-decomposition.md`.

### `kennel-config`

**Purpose.** Layered deployment/user configuration (`#![forbid(unsafe_code)]`), so no install-specific path is baked into a binary.

**Public surface.**
- `Deployment` — integrity-sensitive paths (`libexec_dir`, `trust_dir`, `sshd`, and the resolved helper-binary paths `privhelper` / `netproxy` / `ssh_reorigin` / `socks_connect` / `akc`), loaded from **root-owned** dirs only (`/usr/lib/kennel` then `/etc/kennel`); `load` / `load_from_dirs` / `defaults`.
- `User` — CLI conveniences (`template_dirs`, `key_dirs`), loaded from `~/.config/kennel` then `/etc/kennel` then `/usr/lib/kennel`; `load` / `load_from_dirs`.
- `ConfigError` — load/parse failure modes.

**Depends on.** Stdlib + the TOML parser.

**Depended on by.** `kenneld` (resolves the helper/trust paths at startup).

### `kennel-text`

**Purpose.** Text-sanitisation helpers used wherever untrusted bytes might enter user-visible output.

**Public surface.**
- `display_untrusted(s: &str) -> Untrusted<'_>` — the helper from CODING-STANDARDS.md §10.4.
- `Untrusted` — the wrapper type with a `Display` impl that escapes and delimits.
- `sanitise_for_audit(s: &str) -> String` — for audit JSONL string fields.
- `sanitise_for_log(s: &str) -> String` — for stderr/stdout.

**Depends on.** Stdlib only.

**Depended on by.** `kennel-audit` (the single sanitisation pass on every event); other crates that emit untrusted text reach it transitively through the audit writer.

**Notes.** Tiny crate; deliberately separate so the helpers are easy to find, easy to test (fuzz target included), and reviewable in one read.

### `kenneld` (library + binaries)

**Purpose.** The per-user supervisor. The crate has a library half (`src/lib.rs`) providing the kennel registry and per-kennel orchestration, plus two binaries: `src/bin/kenneld.rs` (the daemon) and `src/bin/kennel.rs` (the CLI). It owns the control protocol, the per-kennel teardown, and the BPF ringbuf audit reader.

**Public surface (library).**
- `Kennel` — a live kennel; `Kennel::stop(&P)` performs immediate teardown (proxy reaped, addresses removed, cgroup deleted), returning the workload's exit status. There is no grace period, no draining state, and no reference counting: one `kennel run` is one kennel.
- `serve(shared, listener)` — the accept loop; it spawns one thread per accepted connection (blocking, no async runtime).
- `control` — the CLI ↔ daemon wire protocol: `Request`/`Response` plus length-prefixed `read_frame`/`write_frame` (native-endian, `MAX_MESSAGE`-bounded). The workload's stdio is passed from the CLI over `SCM_RIGHTS`.
- `socket` — obtains the control listener (the socket-activation fd if present, else a fresh bind at the same path).
- `proxy` — writes the per-kennel egress-proxy TOML config the netproxy reads.

**Public surface (binaries).** `kenneld` is socket-activated (systemd passes the bound listener as fd 3) and serves the control protocol; `kennel` is the CLI client documented in `02-1-cli.md`. The CLI parses its own arguments with hand-rolled `std::env::args` dispatch (no `clap`).

**Depends on.** `kennel-policy`, `kennel-spawn` (kenneld performs the spawn on the CLI's behalf), `kennel-privhelper` (the library half + the binary, for privileged operations), `kennel-audit` (builds the `Writer` from the settled `AuditRuntime`), `kennel-config` (resolves helper/trust paths), `kennel-syscall` (`SCM_RIGHTS`, the few syscalls outside spawn), `serde` + `basic-toml` (writing the proxy config).

**Notes.** The control protocol and the privhelper wire (`kennel-privhelper::wire`) are the natural fuzz-target homes. There is no separate `kennel-ipc-*` or `kennel-cli` crate — both are folded here. The Rust checksum-manifest verifier is also not a crate: the shell witness in `src/tools/verify-checksums.sh` (system `sha256sum`) is what runs today; a Rust twin is a roadmap item.

### `kennel-ssh-reorigin`

**Purpose.** The SSH re-origination forced command (`07-8-ssh.md` §7.8.4). The per-kennel bastion runs it as the forced `command=` bound to a synthetic key; `--dest` and `--key` are baked in by kenneld, so a workload holding a synthetic key can only ever reach the one destination with the one real key.

**Public surface (binary + library).** The library half (`src/lib.rs`) is the security-load-bearing, pure, unit-tested core: strict option-injection-proof `--dest`/`--key` parsing, the hostname and `SHA256:` grammars, `$SSH_USER_AUTH` publickey confirmation (fail-closed), fingerprint→agent-identity selection, and `--`-terminated outbound-`ssh` argv construction. `main.rs` is the thin IO tail (`ssh-add` enumeration, identity-file write, `execvp ssh`).

**Depends on.** **Std only — no Project Kennel crates and no external crates.** The forced command must stay minimal and auditable. Carries no key material (only the public half of the selected key is written).

### `kennel-socks-connect`

**Purpose.** A minimal SOCKS5 CONNECT stdio proxy — the `ssh` `ProxyCommand` a confined kennel uses to reach the bastion through the egress proxy (a kennel can `connect()` only to its proxy, and `ssh` has no built-in SOCKS client).

**Public surface (binary + library).** The library half (`src/lib.rs`) is the pure SOCKS5 wire codec (greeting, CONNECT for IPv4/IPv6/domain, reply parsing), unit-tested. `main.rs` does the TCP connect and bidirectional stdio splice.

**Depends on.** **Std only — no Project Kennel crates and no external crates.**

---

## Crate-level invariants

Per CODING-STANDARDS.md §3:

- Every crate has `#![forbid(unsafe_code)]` at the top of `lib.rs` or `main.rs` *except* `kennel-syscall` (and `kennel-bpf` for its hand-rolled `bpf(2)` FFI surface), which carry `#![allow(unsafe_code)]` and are listed in `UNSAFE-CRATES.md`.
- Every `pub` item carries a doc comment per §6.2.
- Every crate's `lib.rs` carries the module-level doc comment per §6.1 — Purpose, Invariants, Threat bearing, Non-goals.

The `Invariants` block of `kennel-policy` includes the cryptographic-minimums clause from `00-overview.md`'s example (which is itself drawn from this crate's actual public commitment).

---

## What this chapter does not cover

- Dependency graph between crates (acyclic, layered): `03-crate-decomposition.md`.
- Build-time feature flags (bubblewrap composition, audit-format toggles): `03-crate-decomposition.md` and `06-build-and-test.md`.
- Per-crate test placement (unit vs integration, root-required vs not): `06-build-and-test.md`.
- Which crates are published to crates.io (currently: none; the workspace is internal): `06-build-and-test.md`.
- Per-crate ownership and review expectations: implicit from CODING-STANDARDS.md §13; explicit list lives in `MAINTAINERS.md`.
