# API surfaces — internal Rust API

The workspace has 14 crates: `kennel-lib-policy`, `kennel-lib-syscall`, `kennel-lib-bpf`, `kennel-lib-binder`, `kennel-lib-audit`, `kennel-lib-config`, `kennel-lib-spawn`, `host-netproxy`, `kennel-privhelper`, `kennel-bin-init`, `kenneld`, `kennel-lib-text`, `kennel-bin-ssh-reorigin`, and `kennel-socks-connect`. (`kennel-lib-binder` and `kennel-bin-init` are built; `facade-netshim`, the fifteenth, is roadmap — see below.) The control protocol (CLI ↔ kenneld) lives in `kenneld::control`; the privhelper wire protocol in `kennel-privhelper::wire`; the binder logic in `kenneld::binder`; the `kennel` CLI is `kenneld/src/bin/kennel.rs`. `kennel-lib-audit` is the unified audit writer (a first-class crate); `kennel-lib-config` is the layered deployment/user configuration. Everything is blocking, thread-per-connection — there is no async runtime in the workspace. The authoritative per-crate API is the rustdoc (`cargo doc --no-deps`); this chapter is the review-boundary index.

## Stability commitment

**Unstable** per `02-0-overview.md`. Crate-to-crate APIs in the Project Kennel workspace are not commitments to external consumers. They are documented here as *review boundaries*: when a maintainer changes a crate's public surface, the change is visible at compile time across the workspace, and the documentation here helps reviewers understand what changed and why.

External parties may not write code that depends on these surfaces; consumers of the project use the stable surfaces (CLI, policy schema, audit JSONL) instead. If a consumer's use case is not served by any stable surface, the right response is to propose a stable surface, not to depend on an internal crate.

This chapter is a high-level index. The authoritative description of each crate's public API is the rustdoc generated from the crate's source (`cargo doc --no-deps`), with each `pub` item documented per CODING-STANDARDS.md §6.

---

## Crate index

The full workspace layout — directory structure, dependency graph, build feature flags — is in `03-crate-decomposition.md`. This section enumerates the crates and the *shape* of each public API surface.

### `kennel-lib-policy`

**Purpose.** Parsing, template inheritance, signature verification, invariant validation for the policy TOML schema.

**Public surface.** (Exports from `lib.rs`; the resolved types are `EffectivePolicy` / `SettledPolicy` / `ResolvedChain` — there is no `Policy`, `RawPolicy`, `TemplateChain`, or `InstallConstants` type.)
- `SourcePolicy` (`source` module) — the parsed-but-unresolved source artefact (a template or leaf), with `parse(&[u8])` and `SourcePolicy::validate`.
- `ResolvedChain` / `resolve` / `resolve_verified` (`resolve` module) — chain-walk + include-merge to an effective `SourcePolicy`; `TemplateSource` is the artefact-fetch trait the resolver pulls parents/fragments through.
- `EffectivePolicy` — the flat, runtime-enforced rule sets (net/fs/exec/proc/cap/seccomp/lifecycle), the body of a settled policy (the translation target).
- `SettledPolicy` / `SignedSettledPolicy` — the flat, signed runtime artefact (`02-2-config-schema.md` §The settled policy). What `kennel-lib-spawn` consumes. The per-kennel `SshRuntime` / `UnixRuntime` / `IdentityRuntime` / `AuditRuntime` / `EnvRuntime` service inputs ride alongside the `EffectivePolicy` in the settled document.
- `PolicyError` — every failure mode (parse, source-validation, translation, missing template, signature failure, lockfile mismatch, invariant violation, …).
- `compile` / `compile_leaf` / `seal_unsigned` / `Compiled` (`compile` module) — resolve → validate invariants → translate → produce the (un)signed settled document.
- `sign_settled(policy, key)` and `verify_settled(bytes, keys) -> Result<SettledPolicy, PolicyError>` — the latter is the runtime entry point: one signature verification, schema-version gate, framework-invariant re-assertion.
- `validate` / `InvariantViolation` (`invariant` module) — framework-invariant assertion over a settled policy.
- `KeySet` / `SigningKey` (`keys`), `Lockfile` / `LockEntry` (`lock`), `parse_leaf` / `LeafPolicy` (`leaf`).

**Depends on.** `serde`, `basic-toml` (both source and settled policies are TOML — no JSON), and the vetted `ed25519-compact` verifier. No Project Kennel crates — it is pure and I/O-free (callers read bytes from disk and pass them in).

**Depended on by.** The crates that read policy: `kennel-lib-spawn` (consumes `SettledPolicy` via `verify_settled`) and `kenneld` (its `policy` module verifies; the `kennel compile` path in `src/bin/kennel.rs` drives `compile`/`sign_settled`). `host-netproxy` does **not** link it — the proxy parses its own per-kennel config.

**Notes.** This crate's public surface is the largest and most-consumed in the workspace. The `resolve`/`compile` path (heavy: parsing arbitrary templates, chain-walking, crypto) is exercised at compile time; the `verify_settled` path (light: one signature) is what runs on every spawn.

### `kennel-lib-spawn`

**Purpose.** Translates a verified `SettledPolicy` into the actual setup sequence: framework-invariant re-assertion, per-instance substitution, namespaces, mounts, Landlock ruleset, seccomp BPF, capability drop, `PR_SET_NO_NEW_PRIVS`, environment construction, `execve`. It consumes settled policies, not source policies — it does not link the template/resolution machinery.

**Public surface.** (Free functions over a `Plan`, not a `Spawn`/`Workload` builder.)
- `Plan` (`plan` module) — the translated set of kernel-enforcement objects (bind mounts, the shim view, the proxy endpoint, namespaces, the Landlock/seccomp inputs). Built by `Plan::from_policy`. Re-exported alongside `BindMount`, `ProxyEndpoint`, `ShimView`.
- `RuntimeSubstitutions` — the per-instance values (`ctx`, `uid`, `kennel`, `home`, `namespace`, `tag`) the runtime fills into a settled policy's deferred placeholders.
- `substitute(policy, subst) -> Result<SettledPolicy, SpawnError>` — fill the deferred placeholders and refuse any that remain.
- `prepare(bytes, keys, subst) -> Result<Plan, SpawnError>` — the runtime entry point: `verify_settled` the bytes, substitute, translate into a `Plan`.
- `spawn(plan, command) -> Result<Child, SpawnError>` and `spawn_with_gid_map(plan, command, map_gids)` — apply the irreversible seal in the forked child immediately before `execve`; the `gid_map` variant runs the §7.4.8 privileged `gid_map` handshake on a servicer thread.
- `SpawnError` variants for every failure point, including `Policy` (verification), `UnsubstitutedPlaceholder` (boundary 13 in `04-trust-boundaries.md`), and `Syscall`.
- `wire` (`wire` module) — the flat `Plan` codec for the cross-process boundary: kenneld holds the full `Plan` and splits it two ways across the construction handoff (`07-2-kennel-bin-init.md`). The construction-half rides the privhelper `ConstructKennel` op (parsed host-side); the supervision-half is the `GET_SANDBOX_PLAN` reply `kennel-bin-init` pulls over binder and decodes post-pivot. Both decoders are bounded and fuzzed (CODING-STANDARDS §10.6).
- `spawn_sealed` / `fork_into_pid1` (over `kennel-lib-syscall`) — the seal `kennel-bin-init` reuses on the workload child (the irreversible drop → `no_new_privs` → seccomp → Landlock → ulimits → pty → `execve`).

**Depends on.** `kennel-lib-policy` (for `SettledPolicy` and `verify_settled`), `kennel-lib-syscall`, `kennel-lib-bpf`. `#![forbid(unsafe_code)]` — every syscall routes through `kennel-lib-syscall`/`kennel-lib-bpf`. The namespace/mount phase is built in-crate over `kennel-lib-syscall` (bubblewrap-style, identity-mapped user namespace); there is no subprocess delegation to an external composer.

**Depended on by.** `kenneld` (performs the spawn on the CLI's behalf and owns the full `Plan`; the CLI passes the workload's stdio over `SCM_RIGHTS` and kenneld runs the spawn sequence) and `kennel-bin-init` (reuses the seal and decodes the supervision-half `wire` bytes post-pivot).

### `host-netproxy`

**Purpose.** SOCKS5/HTTP proxy enforcing the per-destination network allowlist. A binary crate (`main.rs`) with a library half (`lib.rs`) so the server, allowlist evaluator, and audit formatter are unit-testable without the network.

**Public surface.** The proxy reads its per-kennel TOML config (written by kenneld) at startup. The server lives in `src/server.rs`/`socks5.rs`/`http.rs`, the allowlist evaluator in `src/allow.rs`, and the JSONL audit formatter in `src/audit.rs` (one record per request; the server owns the sink — a per-kennel file wired by kenneld, or stderr). Blocking, one thread per connection.

**Depends on.** `kennel-lib-audit` (the egress records go through the unified `Writer`). It does **not** link `kennel-lib-policy`: the proxy parses its own per-kennel TOML config (`src/config.rs`) rather than the source/settled schema. No async runtime — the proxy is deliberately built without a `tokio`/`mio` tree (see `03-crate-decomposition.md`).

**Depended on by.** `kenneld` links the crate (it shares config types and invokes the binary per kennel).

**Roadmap (the net-ns redesign, `02-5-binder-net.md` §Relationship to `host-netproxy` crate).** When the per-kennel network namespace lands, the proxy's inbound half changes: it stops being reached by a TCP loopback SOCKS5 listener and instead becomes kenneld's **CONNECT delegate**. The SOCKS5 accept half (`src/server.rs` inbound) moves out to the new `facade-netshim` crate (inside the kennel net-ns); `host-netproxy` keeps the outbound dial, allowlist, DNS-vetting, and audit logic unchanged but gains a **delegate-socketpair reader** in place of the SOCKS5 listener — one reader thread on the `kenneld`↔delegate `socketpair`, dispatching a worker per `CONNECT` request that returns the connected fd by `SCM_RIGHTS`. It stays `#![forbid(unsafe_code)]` and **does not** link `kennel-lib-binder` (binder stays confined to kenneld + `facade-netshim`); `[net]` becomes `[net.proxy]` in its config reader.

### `facade-netshim` *(roadmap — not yet built)*

**Purpose.** The kennel-side network shim introduced by the net-ns redesign (`02-5-binder-net.md`). A thin process inside the kennel net-ns: SOCKS5 inbound state machine, binder `INet` consumer, splice loop — it carries no policy. It is the new home of the SOCKS5 accept half that leaves `host-netproxy`, and the only roadmap process that links `kennel-lib-binder`.

**Public surface (planned).** A binary crate with a library half: the SOCKS5 state machine (an untrusted-input parser of workload SOCKS5 requests — a fuzz target under `fuzz/` per CODING-STANDARDS §10.6), the `org.projectkennel.INet/default` consumer (`getService`, the `CONNECT`/`INBOUND` transactions), and the per-connection splice loop. One listener thread on `:1080`; one thread per accepted connection, each issuing one blocking binder transaction.

**Depends on (planned).** `kennel-lib-binder` (the `INet` consumer client). Carries no policy and links no `kennel-lib-policy`.

**Depended on by.** Nothing — a standalone binary the in-kennel reaper forks into the kennel's namespaces and view.

### `kennel-lib-bpf`

**Purpose.** BPF program loader. Owns the `.bpf.o` files and a hand-rolled `bpf(2)` loader over `libc`, using `object` only for ELF parsing — **not** libbpf-rs/libbpf-sys or aya (which would pull in a large C-vendoring or crate tree). The map definitions live in Rust (`KENNEL_MAPS`), mirroring `bpf/maps.h`; the programs compile against the kernel UAPI (no CO-RE), so the loader only resolves map relocations by symbol name.

**Public surface.** (There is no `BpfRuntime` handle, no `attach_to_cgroup`, and no `next_audit_event` — the surface is a loader plus a ringbuf reader.)
- `load_program` / `Loaded` (`loader` module) — load and relocate one compiled program object; `Loaded` holds the resulting program/map fds.
- `MapSpec` / `ProgramSpec` and the `KENNEL_MAPS` / `KENNEL_PROGRAMS` tables — the Rust descriptions of the maps and programs, mirroring `bpf/maps.h`.
- `RingBuffer` (`ringbuf` module) — the lock-free `mmap`'d audit-event drain (drops on a full buffer). The reader exists in this crate; kenneld does not yet drive it (see the note under `kennel-lib-audit` and `03-crate-decomposition.md`).
- `programs::object(name)` — the embedded compiled `.o` bytes, available only under the `embed-programs` feature.

**Depends on.** `object` (ELF parsing) and `libc` (the `bpf(2)` FFI; `kennel-lib-bpf` is the second `unsafe` crate). It does **not** depend on `kennel-lib-policy`; the egress map entries are built by `kennel-lib-spawn::plan` and carried over the privhelper wire.

**Depended on by.** `kennel-privhelper` *optionally* (under `bpf-egress`, for the egress load/attach). `kennel-lib-spawn` references it for the egress map-entry types; the actual cgroup attach is done by the privhelper, not in `kennel-lib-spawn`. The ringbuf reader is present but not yet wired into kenneld.

**Notes.** Crate-level `#![allow(unsafe_code)]` for the `bpf(2)` FFI boundary (confined to `sys.rs`); reviewed under §4. ELF parsing is delegated to `object`.

### `kennel-lib-binder`

**Purpose.** The hand-rolled binder ioctl ABI — the third `unsafe`-bearing crate, structurally parallel to `kennel-lib-bpf` (`02-4-binder.md` §The `kennel-lib-binder` crate). It owns the kernel-ABI *mechanism*; policy and state live in `kenneld::binder`. Built (the inter-namespace gateway core is proven by the unprivileged vertical); the cross-instance relay and the `INet` network crossing it will also carry are roadmap.

**Public surface.** (Mechanism only — no policy; the surface is a context-manager primitive plus the command-stream codec.)
- The `binder_write_read` command loop and the `BC_*`/`BR_*` / `binder_transaction_data` encode/decode. The `BC_*`/`BR_*` decoder consumes workload-controlled bytes — an untrusted-input parser carrying a fuzz target under `fuzz/` per CODING-STANDARDS §10.6.
- The context-manager looper primitive: looper registration (`BC_ENTER_LOOPER`), transaction receive, reply dispatch (`BC_REPLY`), `BINDER_SET_CONTEXT_MGR` / `BINDER_SET_MAX_THREADS`.
- binderfs device allocation (the binderfs control `BINDER_CTL_ADD`) and death-notification plumbing.
- `BINDER_VERSION` (checked at open — protocol version 8).

**Depends on.** `libc`/`nix` for the syscalls; optionally `kennel-lib-syscall` for shared raw-fd helpers. Like `kennel-lib-bpf` it depends on no other Project Kennel crate of substance, and it does **not** link `object` (binder is an ioctl ABI, not an object format) nor any `libbinder`/`libbinder-ndk` (both carry Android-specific dependencies — the stable UAPI is bound directly).

**Depended on by.** `kenneld` (the `binder` module — node 0, the registry, the looper), `kennel-bin-init` (the lifecycle consumer; see below), and — roadmap — `facade-netshim` (the `INet` consumer). No other process links it; binder participation is confined to these three.

**Notes.** Crate-level `#![allow(unsafe_code)]`, confined to a single `sys.rs` holding the `ioctl(2)` FFI; listed in `UNSAFE-CRATES.md`; reviewed under §4. The `kennel-lib-binder`↔`kenneld::binder` split mirrors `kennel-lib-bpf`↔`kenneld`: the crate provides the primitive, kenneld decides what to register/resolve and drives the looper.

### `kennel-privhelper`

**Purpose.** The privileged binary. Reads a fixed-layout request from stdin, validates it, performs one network/cgroup operation, writes a response to stdout, exits.

**Public surface (binary + library).** The wire format is fixed-size packed structs in the `wire` module (`src/wire.rs`), documented in `02-6-ipc.md` under "kenneld ↔ privhelper protocol". The crate's library half exposes `wire` and `validate` (the request frame and its validation core), `addr` and `alloc` (the address/allocation maths the validator and `kenneld` share), `client` (the helper-invocation client `kenneld` links), and `exec` (the privileged-syscall execution, Linux-only). It is tested in-crate.

Beyond the fixed-layout stdin/stdout ops (the network/cgroup ops), the privhelper is now the kennel **constructor** (the uid-0/`kennel-bin-init` inversion, `07-2-kennel-bin-init.md`). The `ConstructKennel` op runs over a `SOCK_SEQPACKET` socketpair (not stdin/stdout) so it can carry fds via `SCM_RIGHTS`: it takes the construction-half `kennel-lib-spawn::wire` `Plan` in, clones the namespaces (as the operator, so the userns is operator-owned), escalates the child to the kennel's uid 0 to build the root-owned surfaces and mount/chown binderfs, `pivot_root`s, drops to the operator, `fexecve`s the trusted root-owned `kennel-bin-init`, and relays the init/workload host pids and exit status back. (The `0 0 1` map write needs `CAP_SETUID`, so the privhelper's file caps grow accordingly — see `07-paths.md`.) The detailed wire is `02-6-ipc.md`.

**Depends on.** `kennel-lib-syscall` (for the privileged syscalls — netlink address ops), and an **optional** `kennel-lib-bpf` pulled in only under the `bpf-egress` feature (for the egress load/attach). Not `kennel-lib-text` and not `serde`: the IPC is fixed-layout packed structs over stdin/stdout (`wire`, packed field-by-field), and the validation core is std-only — so the crate stays `#![forbid(unsafe_code)]`. A plain build links neither `kennel-lib-bpf` nor clang.

**Depended on by.** `kenneld` links the crate's library half (`wire`/`validate`/`client`) to drive the helper; it also invokes the binary.

**Notes.** Compiled with `[profile.release] panic = "abort"`; `[profile.test] panic = "unwind"` per CODING-STANDARDS.md §8.5. `clippy::expect_used` is `deny` in this crate per §8.3.

### `kennel-bin-init`

**Purpose.** The kennel's PID 1 — a root-owned trusted binary the privhelper factory `fexecve`s after it constructs the namespaces and writes the maps (design [`07-2-kennel-bin-init.md`](../design/07-2-kennel-bin-init.md); as-built fork tree in [`01-process-model.md`](01-process-model.md)). It is the lifecycle consumer of the binder bus: it opens `/dev/binderfs/binder`, **pulls** its supervision-half of the `Plan` from node 0 via `GET_SANDBOX_PLAN`, builds the inner surfaces, forks the facades and the workload (dropped to the operator), and supervises. Built (PID 1 + the `GET_SANDBOX_PLAN` pull + the `NOTIFY_*` lifecycle verbs are proven by the unprivileged vertical).

**Public surface (binary + library).** The library half is the small, security-load-bearing core: the post-pivot `GET_SANDBOX_PLAN` pull and bounded decode of the supervision-half `kennel-lib-spawn::wire` bytes (a fuzzed untrusted-input parser per CODING-STANDARDS §10.6), the `NOTIFY_BOOT_SYNC` / `NOTIFY_FACADE_CRASH` / `NOTIFY_WORKLOAD_EXEC` lifecycle verbs it issues to node 0, and the fork-and-drop sequence for the facades and the workload. `main.rs` is the PID-1 tail (open the device, pull, supervise, reap, relay exit status). The workload child reuses the `kennel-lib-spawn` seal (`spawn_sealed`) for the irreversible drop → `no_new_privs` → seccomp → Landlock → ulimits → pty → `execve`.

**Depends on.** `kennel-lib-binder` (the lifecycle consumer's binder client), `kennel-lib-spawn` (the seal applied to the workload child), and `kennel-lib-syscall` (the fork/drop/pty primitives). `#![forbid(unsafe_code)]` — every syscall routes through `kennel-lib-syscall`. It runs no mount/netlink/device/fs-lookup/env code; its path comes from `Deployment` (`kennel-lib-config`), never the wire.

**Depended on by.** Nothing links it — it is a standalone binary the privhelper opens (pre-clone, by root-owned non-writable path) and `fexecve`s. It runs as the kennel's **uid 0** (a different uid from the operator-uid workload/facades, so they cannot signal or `ptrace` PID 1); it drops each child it forks to the operator.

### `kennel-lib-syscall`

**Purpose.** One of the two crates permitted to contain `unsafe` blocks (the other is `kennel-lib-bpf`). Wraps raw Linux syscalls, namespace operations, Landlock primitives, seccomp installation, and capability manipulation. (The `bpf(2)` FFI lives in `kennel-lib-bpf`, not here.)

**Public surface.** A module per concern, each a safe wrapper over the raw syscalls: `landlock` (the `Ruleset` builder + `Scope`/`AccessFs`/`AccessNet`), `namespace` (the userns/mount/PID unshare and `establish_identity_userns`), `mount`, `seccomp`, `process` (`set_no_new_privs`), `path` (canonical-path resolution), `netlink` (the privhelper's address ops), `scm` (`SCM_RIGHTS`), `pty` (controlling-terminal allocation + the in-view interactive pty hand-off, design §7.9.5a), `signal`, `spawn` (`spawn_sealed`, `fork_into_pid1`), `handshake`, `listenfd`, `unistd`, and — for `kennel-lib-audit` — `journal` (journald FFI) and `random` (UUIDv7 randomness).

**Depends on.** `nix`, `libc`. (`kennel-lib-bpf` builds its `bpf(2)` FFI on `libc` + `object` directly, not on a `-sys` crate.)

**Depended on by.** `kennel-lib-spawn`, `kennel-privhelper`, `kenneld`, and `kennel-lib-audit` (the latter only under `audit-journald`, for the journald FFI and the UUIDv7 randomness). Notably **not** `kennel-lib-policy`, which is pure and links no Project Kennel crate.

**Notes.** Crate-level `#![allow(unsafe_code)]`; every `unsafe` block follows the comment template in §4. The crate is partitioned a module per concern so each `unsafe` surface is reviewable on its own.

### `kennel-lib-audit`

**Purpose.** The unified audit writer (`#![forbid(unsafe_code)]`): the seam between audit *sources* (the BPF drain, the netproxy, the privhelper, the spawn wrapper, kenneld) and audit *sinks* (file, stdout, syslog, and — feature `audit-journald` — journald). A source builds an `Event`; the `Writer` stamps the envelope, runs one `kennel-lib-text` sanitisation pass, applies the per-class `Level`, and fans the rendered record out to every configured `Sink`.

**Public surface.**
- `Event` / `Level` / `Outcome` / `Resource` / `Source` / `Value` (`event` module) — the event schema; the durable contract is `02-3-audit-schema.md`.
- `Writer` / `WriterContext` / `Levels` / `Sink` / `SinkError` (`writer` module) — the writer, its build-time context, and the sink trait; `MAX_EVENT_BYTES` / `SCHEMA_VERSION` constants.
- `FileSink` / `StdoutSink` / `SyslogSink` (`sinks`), `TimeoutSink` (`timeout`), and `JournaldSink` under `audit-journald`.
- `SinkConfig` / `SinkKind` / `facility_code` / `hostname` (`build`), `Record` / `Rendered` (`render`), `format_uuid_v7`, `Clock` / `SystemClock` / `format_rfc3339_micros` (`time`).

**Depends on.** `kennel-lib-text` (the single sanitisation pass). The journald FFI and the UUIDv7 randomness — the only parts needing `unsafe`/FFI — live in `kennel-lib-syscall` (`journal`, `random`), not here.

**Depended on by.** `kenneld` (builds the `Writer` from the settled `AuditRuntime`, emits lifecycle events) and `host-netproxy` (builds its own `Writer` from the per-kennel proxy config, emits each `net.egress` record). Not yet routed through the writer: the BPF ringbuf events — a roadmap remnant; see `03-crate-decomposition.md`.

### `kennel-lib-config`

**Purpose.** Layered deployment/user configuration (`#![forbid(unsafe_code)]`), so no install-specific path is baked into a binary.

**Public surface.**
- `Deployment` — integrity-sensitive paths (`libexec_dir`, `trust_dir`, `sshd`, and the resolved helper-binary paths `privhelper` / `netproxy` / `ssh_reorigin` / `socks_connect` / `akc`), loaded from **root-owned** dirs only (`/usr/lib/kennel` then `/etc/kennel`); `load` / `load_from_dirs` / `defaults`.
- `User` — CLI conveniences (`template_dirs`, `key_dirs`), loaded from `~/.config/kennel` then `/etc/kennel` then `/usr/lib/kennel`; `load` / `load_from_dirs`.
- `ConfigError` — load/parse failure modes.

**Depends on.** Stdlib + the TOML parser.

**Depended on by.** `kenneld` (resolves the helper/trust paths at startup).

### `kennel-lib-text`

**Purpose.** Text-sanitisation helpers used wherever untrusted bytes might enter user-visible output.

**Public surface.**
- `display_untrusted(s: &str) -> Untrusted<'_>` — the helper from CODING-STANDARDS.md §10.4.
- `Untrusted` — the wrapper type with a `Display` impl that escapes and delimits.
- `sanitise_for_audit(s: &str) -> String` — for audit JSONL string fields.
- `sanitise_for_log(s: &str) -> String` — for stderr/stdout.

**Depends on.** Stdlib only.

**Depended on by.** `kennel-lib-audit` (the single sanitisation pass on every event); other crates that emit untrusted text reach it transitively through the audit writer.

**Notes.** Tiny crate; deliberately separate so the helpers are easy to find, easy to test (fuzz target included), and reviewable in one read.

### `kenneld` (library + binaries)

**Purpose.** The per-user supervisor. The crate has a library half (`src/lib.rs`) providing the kennel registry and per-kennel orchestration, plus three binaries: `src/bin/kenneld.rs` (the daemon), `src/bin/kennel.rs` (the CLI), and `src/bin/kennel-akc.rs` (the root-owned `AuthorizedKeysCommand` helper that queries the running daemon for the SSH egress bastion; see `07-10`). It owns the control protocol and the per-kennel teardown. Draining the BPF ringbuf into the audit writer is not yet wired here (a roadmap remnant; see the `kennel-lib-audit` note and `03-crate-decomposition.md`).

**Public surface (library).**
- `Kennel` — a live kennel; `Kennel::stop(&P)` performs immediate teardown (proxy reaped, addresses removed, cgroup deleted), returning the workload's exit status. There is no grace period, no draining state, and no reference counting: one `kennel run` is one kennel.
- `serve(shared, listener)` — the accept loop; it spawns one thread per accepted connection (blocking, no async runtime).
- `control` — the CLI ↔ daemon wire protocol: `Request`/`Response` plus length-prefixed `read_frame`/`write_frame` (native-endian, `MAX_MESSAGE`-bounded). The workload's stdio is passed from the CLI over `SCM_RIGHTS`.
- `socket` — obtains the control listener (the socket-activation fd if present, else a fresh bind at the same path).
- `proxy` — writes the per-kennel egress-proxy TOML config the netproxy reads.
- `binder` — kenneld's context-manager logic over the `kennel-lib-binder` primitive (`#![forbid(unsafe_code)]`): node-0 acquisition (open `/proc/<init-host-pid>/root/dev/binderfs/binder` for the operator-owned instance, then `BINDER_SET_CONTEXT_MGR`), the per-instance non-blocking looper, the per-kennel and (roadmap) cross-instance service registries, the `org.projectkennel.*` reserved services (the built `IAfUnix/default` facade; roadmap `INet`), the `GET_SANDBOX_PLAN` reply that hands `kennel-bin-init` its supervision-half `Plan`, and the `NOTIFY_*` lifecycle verbs gated on `sender_pid == init_host_pid && sender_euid == 0`. The full contract is `02-4-binder.md`; the network-over-binder half is `02-5-binder-net.md`.

The **kenneld↔delegate socketpair protocol** *(roadmap — `02-5-binder-net.md`)* is how kenneld reaches the non-binder network delegates: `host-netproxy` (the CONNECT delegate) and the host-side spawn leg (the BIND/mirror delegate) are **not** binder participants. kenneld's looper runs the O(1) policy check on each `INet` transaction, records a pending entry keyed by the binder transaction cookie, and forwards `{cookie, payload, target}` to the right delegate over a per-kennel `socketpair` established at spawn; the delegate does the blocking dial/bind and returns the fd by `SCM_RIGHTS`; kenneld's reply-reader matches the cookie and issues `BC_REPLY` carrying the fd via `BINDER_TYPE_FD`. A slow delegate degrades to a refusal on that one instance (bounded pending-cookie table), never a looper stall.

**Public surface (binaries).** `kenneld` is socket-activated (systemd passes the bound listener as fd 3) and serves the control protocol; `kennel` is the CLI client documented in `02-1-cli.md`. The CLI parses its own arguments with hand-rolled `std::env::args` dispatch (no `clap`).

**Depends on.** `kennel-lib-policy`, `kennel-lib-spawn` (kenneld performs the spawn on the CLI's behalf, and holds the full `Plan` it splits between the privhelper construction-half and the `kennel-bin-init` supervision-half), `kennel-privhelper` (the library half + the binary — now the kennel *constructor*: it drives the `ConstructKennel` op that clones the namespaces and `fexecve`s `kennel-bin-init`), `kennel-lib-binder` (the context-manager primitive driven by `kenneld::binder`), `kennel-lib-audit` (builds the `Writer` from the settled `AuditRuntime`), `kennel-lib-config` (resolves helper/trust paths, incl. the `kennel-bin-init` binary path), `kennel-lib-syscall` (`SCM_RIGHTS`, the few syscalls outside spawn), `serde` + `basic-toml` (writing the proxy config). It does **not** link `kennel-bin-init` (a standalone binary the privhelper `fexecve`s) nor — roadmap — `facade-netshim`.

**Notes.** The control protocol and the privhelper wire (`kennel-privhelper::wire`) are the natural fuzz-target homes. There is no separate `kennel-ipc-*` or `kennel-cli` crate — both are folded here. The Rust checksum-manifest verifier is also not a crate: the shell witness in `src/tools/verify-checksums.sh` (system `sha256sum`) is what runs today; a Rust twin is a roadmap item.

### `kennel-bin-ssh-reorigin`

**Purpose.** The SSH re-origination forced command (`07-10-ssh.md` §7.10.4). The per-kennel bastion runs it as the forced `command=` bound to a synthetic key; `--dest` and `--key` are baked in by kenneld, so a workload holding a synthetic key can only ever reach the one destination with the one real key.

**Public surface (binary + library).** The library half (`src/lib.rs`) is the security-load-bearing, pure, unit-tested core: strict option-injection-proof `--dest`/`--key` parsing, the hostname and `SHA256:` grammars, `$SSH_USER_AUTH` publickey confirmation (fail-closed), fingerprint→agent-identity selection, and `--`-terminated outbound-`ssh` argv construction. `main.rs` is the thin IO tail (`ssh-add` enumeration, identity-file write, `execvp ssh`).

**Depends on.** **Std only — no Project Kennel crates and no external crates.** The forced command must stay minimal and auditable. Carries no key material (only the public half of the selected key is written).

### `kennel-socks-connect`

**Purpose.** A minimal SOCKS5 CONNECT stdio proxy — the `ssh` `ProxyCommand` a confined kennel uses to reach the bastion through the egress proxy (a kennel can `connect()` only to its proxy, and `ssh` has no built-in SOCKS client).

**Public surface (binary + library).** The library half (`src/lib.rs`) is the pure SOCKS5 wire codec (greeting, CONNECT for IPv4/IPv6/domain, reply parsing), unit-tested. `main.rs` does the TCP connect and bidirectional stdio splice.

**Depends on.** **Std only — no Project Kennel crates and no external crates.**

---

## Crate-level invariants

Per CODING-STANDARDS.md §3:

- Every crate has `#![forbid(unsafe_code)]` at the top of `lib.rs` or `main.rs` *except* `kennel-lib-syscall`, `kennel-lib-bpf` (its hand-rolled `bpf(2)` FFI surface), and `kennel-lib-binder` (its hand-rolled binder `ioctl(2)` FFI surface), which carry `#![allow(unsafe_code)]` and are listed in `UNSAFE-CRATES.md`.
- Every `pub` item carries a doc comment per §6.2.
- Every crate's `lib.rs` carries the module-level doc comment per §6.1 — Purpose, Invariants, Threat bearing, Non-goals.

The `Invariants` block of `kennel-lib-policy` includes the cryptographic-minimums clause from `00-overview.md`'s example (which is itself drawn from this crate's actual public commitment).

---

## What this chapter does not cover

- Dependency graph between crates (acyclic, layered): `03-crate-decomposition.md`.
- Build-time feature flags (`bpf-egress`, `embed-programs`, audit-format toggles): `03-crate-decomposition.md` and `06-build-and-test.md`.
- Per-crate test placement (unit vs integration, root-required vs not): `06-build-and-test.md`.
- Which crates are published to crates.io (currently: none; the workspace is internal): `06-build-and-test.md`.
- Per-crate ownership and review expectations: implicit from CODING-STANDARDS.md §13; explicit list lives in `MAINTAINERS.md`.
