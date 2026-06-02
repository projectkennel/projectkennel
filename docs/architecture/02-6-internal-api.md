# API surfaces — internal Rust API

> **As-built status (see `08-as-built-notes.md` §8.1).** This chapter is indexed by
> the original ~13-crate decomposition; the as-built workspace has **8** crates.
> The `kennel-audit`, `kennel-ipc-shared`/`-client`/`-server`, and `kennel-cli`
> sections describe components that were **folded** (control protocol →
> `kenneld::control`; privhelper wire → `kennel-privhelper::wire`; CLI →
> `kenneld/src/bin/kennel.rs`; audit → the BPF ringbuf drain + the netproxy
> formatter) or **deferred** (a unified audit crate). There is no async runtime
> (`tokio`) and the CLI uses `lexopt`, not `clap`. The authoritative per-crate API
> is the rustdoc; read the folded/deferred sections through §8.1/§8.2.

## Stability commitment

**Unstable** per `02-0-overview.md`. Crate-to-crate APIs in the Project Kennel workspace are not commitments to external consumers. They are documented here as *review boundaries*: when a maintainer changes a crate's public surface, the change is visible at compile time across the workspace, and the documentation here helps reviewers understand what changed and why.

External parties may not write code that depends on these surfaces; consumers of the project use the stable surfaces (CLI, policy schema, audit JSONL) instead. If a consumer's use case is not served by any stable surface, the right response is to propose a stable surface, not to depend on an internal crate.

This chapter is a high-level index. The authoritative description of each crate's public API is the rustdoc generated from the crate's source (`cargo doc --no-deps`), with each `pub` item documented per CODING-STANDARDS.md §6.

---

## Crate index

The full workspace layout — directory structure, dependency graph, build feature flags — is in `03-crate-decomposition.md`. This section enumerates the crates and the *shape* of each public API surface.

### `kennel-policy`

**Purpose.** Parsing, template inheritance, signature verification, invariant validation for the policy TOML schema.

**Public surface.**
- `Policy` — the resolved (in-memory) policy (post template-chain, post invariant checks). An intermediate produced during compilation, not the runtime artefact.
- `SettledPolicy` — the flat, signed, runtime artefact (`02-2-config-schema.md` §The settled policy). What `kennel-spawn` consumes.
- `RawPolicy` — the parsed-but-unresolved single file. Used by tooling that wants to inspect one file without resolution.
- `TemplateChain` — the ordered set of templates a leaf policy inherits from.
- `PolicyError` — every failure mode (parse, missing template, signature failure, lockfile mismatch, include conflict, invariant violation, …).
- `resolve(leaf: &Path, search_paths: &[PathBuf]) -> Result<Policy, PolicyError>` — chain-walk, include-merge, delta-apply, source-signature and lockfile verification.
- `compile(leaf: &Path, search_paths: &[PathBuf], install_constants: &InstallConstants) -> Result<SettledPolicy, PolicyError>` — resolve, validate invariants, substitute installation constants, produce the unsigned settled document.
- `sign_settled(settled: &SettledPolicy, key: &SigningKey) -> SignedSettledPolicy`.
- `verify_settled(bytes: &[u8], key_set: &KeySet) -> Result<SettledPolicy, PolicyError>` — the runtime entry point: one signature verification, schema-version check. (Framework-invariant re-assertion lives in `kennel-spawn`, which owns the spawn-refusal path.)
- `validate(policy: &Policy) -> Result<(), Vec<InvariantViolation>>`.
- `verify_signature(envelope: &SignatureEnvelope, key_set: &KeySet) -> Result<(), SignatureError>`.

**Depends on.** `kennel-text` (sanitisation), `kennel-syscall` (canonical-path resolution), `serde`, `basic-toml` (both source and settled policies are TOML — no JSON), `ed25519-compact` (the vetted Ed25519 verifier; see `DEPENDENCIES.md`).

**Depended on by.** Every other crate that reads policy: `kennel-spawn` (consumes `SettledPolicy`), `kennel-cli` (`kennel compile` calls `compile`/`sign_settled`), `kenneld`, `kennel-bpf` (loader side).

**Notes.** This crate's public surface is the largest and most-consumed in the workspace. Changes here propagate widely. The `resolve`/`compile` path (heavy: parsing arbitrary templates, chain-walking, crypto) is exercised at compile time; the `verify_settled` path (light: one signature) is what runs on every spawn.

### `kennel-spawn`

**Purpose.** Translates a verified `SettledPolicy` into the actual setup sequence: framework-invariant re-assertion, per-instance substitution, namespaces, mounts, Landlock ruleset, seccomp BPF, capability drop, `PR_SET_NO_NEW_PRIVS`, environment construction, `execve`. It consumes settled policies, not source policies — it does not link the template/resolution machinery.

**Public surface.**
- `Spawn` — builder for the spawn sequence.
- `Workload` — handle to a spawned workload (PID, control handle).
- `spawn(settled: &SettledPolicy, runtime_subst: &RuntimeSubstitutions, command: &Command, env: Env, ...) -> Result<Workload, SpawnError>`.
- `SpawnError` variants for every failure point, including `SettledSignatureFailure`, `FrameworkInvariantViolated`, `UnsubstitutedPlaceholder` (boundary 13 in `04-trust-boundaries.md`).

**Depends on.** `kennel-policy` (for `SettledPolicy` and `verify_settled`), `kennel-syscall`, `kennel-bpf`, `kennel-audit`, optionally `bubblewrap-sys` (build-time feature flag — see `03-crate-decomposition.md`).

**Depended on by.** `kennel-cli` (CLI's spawn path), `kenneld` (when kenneld performs the spawn on the CLI's behalf — currently the CLI does it itself, but the option exists).

### `kennel-netproxy`

**Purpose.** SOCKS5 proxy enforcing per-destination network allowlist. A standalone binary.

**Public surface (binary).** The control protocol described in `02-4-ipc.md` under "kenneld ↔ per-kennel daemons" → netproxy methods. The binary's command-line interface is internal; kenneld invokes it with a fixed flag set.

**Public surface (library, optional).** A `kennel-netproxy-core` crate may be split out to expose the proxy logic as a library for testing; current decision is to keep the proxy as a single binary crate.

**Depends on.** `kennel-policy` (for the network policy fragment), `kennel-audit`, `kennel-text`, an async runtime (one only; see `03-crate-decomposition.md`).

**Depended on by.** Nothing else in the workspace links this crate; kenneld invokes the binary.

### `kennel-bpf`

**Purpose.** BPF program loader. Owns the `.bpf.o` files and a hand-rolled `bpf(2)` loader over `libc`, using `object` only for ELF parsing — **not** libbpf-rs/libbpf-sys or aya (which would pull in a large C-vendoring or crate tree). The map definitions live in Rust (`KENNEL_MAPS`), mirroring `bpf/maps.h`; the programs compile against the kernel UAPI (no CO-RE), so the loader only resolves map relocations by symbol name.

**Public surface.**
- `BpfRuntime` — the runtime handle for one kennel's BPF state (maps, attached programs).
- `BpfRuntime::new(meta: &KennelMeta) -> Result<BpfRuntime, BpfError>`.
- `BpfRuntime::set_allowlist_v4(&mut self, entries: &[AllowEntry])` — etc, one method per map.
- `BpfRuntime::attach_to_cgroup(&self, cgroup_path: &Path) -> Result<(), BpfError>`.
- `next_audit_event(&mut self) -> Option<BpfAuditEvent>` — drains the shared ringbuf.

**Depends on.** `object` (ELF parsing) and `libc` (the `bpf(2)` FFI; see `kennel-syscall`'s `unsafe` policy — `kennel-bpf` is the second `unsafe` crate), `kennel-policy` (for `AllowEntry` and friends).

**Depended on by.** `kennel-spawn` (attaches BPF before exec), `kenneld` (owns the ringbuf reader).

**Notes.** Crate-level `#![allow(unsafe_code)]` for the `bpf(2)` FFI boundary (confined to `sys.rs`); reviewed under §4. ELF parsing is delegated to `object`.

### `kennel-privhelper`

**Purpose.** The privileged binary. Reads JSON from stdin, validates, performs one network/cgroup operation, writes JSON to stdout, exits.

**Public surface (binary).** The wire format documented in `02-4-ipc.md` under "kenneld ↔ privhelper protocol".

**Public surface (library).** None. The privhelper is a binary crate with `main.rs` only; helper functions are `pub(crate)` and tested in-crate.

**Depends on.** `kennel-syscall` (for the privileged syscalls — netlink address ops). The IPC is fixed-layout struct messages over stdin/stdout (the `wire` module; no serde), and the validation core is std-only — so the crate stays `#![forbid(unsafe_code)]`.

**Depended on by.** Nothing in the workspace links this crate.

**Notes.** Compiled with `[profile.release] panic = "abort"`; `[profile.test] panic = "unwind"` per CODING-STANDARDS.md §8.5. `clippy::expect_used` is `deny` in this crate per §8.3.

### `kennel-syscall`

**Purpose.** One of the two crates permitted to contain `unsafe` blocks (the other is `kennel-bpf`). Wraps raw Linux syscalls, namespace operations, Landlock primitives, seccomp installation, and capability manipulation. (The `bpf(2)` FFI lives in `kennel-bpf`, not here.)

**Public surface.** Safe wrappers exposing the operations needed by other crates. Examples: `unshare_mount_namespace()`, `landlock_ruleset_create_and_seal()`, `seccomp_filter_install()`, `prctl_no_new_privs()`, `canonicalise_path(p: &Path, prefix: &Path) -> Result<PathBuf, _>` (the helper from `10.3`/`11.3`).

**Depends on.** `nix`, `libc`. (`kennel-bpf` builds its `bpf(2)` FFI on `libc` + `object` directly, not on a `-sys` crate.)

**Depended on by.** Everything.

**Notes.** Crate-level `#![allow(unsafe_code)]`; every `unsafe` block follows the comment template in §4. The crate is sized to be reviewable in one sitting — target ceiling 1500 lines of Rust.

### `kennel-audit`

**Purpose.** Audit event types and the writer that emits them as JSONL to the per-kennel files.

**Public surface.**
- `AuditEvent` enum, one variant per event type from `02-3-audit-schema.md`.
- `AuditWriter` — the per-kennel writer; owns an `O_APPEND` file handle, rotates at threshold.
- `emit(event: AuditEvent)` — synchronous append.
- `Reader::query(filter: AuditFilter) -> impl Iterator<Item=AuditEvent>` — for `kennel audit` queries.

**Depends on.** `kennel-text` (sanitisation), `time`. Audit events are emitted as JSON Lines by a small hand-rolled writer (the schema is fixed and known — no `serde_json`).

**Depended on by.** `kennel-spawn`, `kennel-netproxy`, `kenneld`, `kennel-bpf` (the ringbuf reader translates BPF events into `AuditEvent`s).

### `kennel-text`

**Purpose.** Text-sanitisation helpers used wherever untrusted bytes might enter user-visible output.

**Public surface.**
- `display_untrusted(s: &str) -> Untrusted<'_>` — the helper from CODING-STANDARDS.md §10.4.
- `Untrusted` — the wrapper type with a `Display` impl that escapes and delimits.
- `sanitise_for_audit(s: &str) -> String` — for audit JSONL string fields.
- `sanitise_for_log(s: &str) -> String` — for stderr/stdout.

**Depends on.** Stdlib only.

**Depended on by.** Everything that emits user-visible or audit output.

**Notes.** Tiny crate; deliberately separate so the helpers are easy to find, easy to test (fuzz target included), and reviewable in one read.

### `kennel-checksum-verify`

**Purpose.** Implements `tools/verify-checksums`, the Rust half of the checksum-manifest verifier (CODING-STANDARDS.md §5.5).

**Public surface (binary).** Command-line: verifies `src/vendor/` against `CHECKSUMS.toml` and `Cargo.lock`.

**Public surface (library).** A small `verify::run(manifest_path, archive_dir, lock_path) -> Result<Report, _>` for embedding in CI helpers.

**Depends on.** `sha2` (which is itself in the checksum manifest; the shell-script verifier in `tools/verify-checksums.sh` is the second witness), `serde`, `toml`.

**Depended on by.** Build tooling, not by any runtime crate.

### `kennel-cli`

**Purpose.** The `kennel` binary's main and subcommand dispatch.

**Public surface (binary).** The CLI documented in `02-1-cli.md`.

**Public surface (library).** None. The CLI is a binary crate; subcommand handlers are `pub(crate)`.

**Depends on.** `kennel-policy`, `kennel-spawn`, `kennel-ipc-client` (see below), `kennel-audit` (for `kennel audit` queries), `kennel-text`, `clap`.

### `kenneld`

**Purpose.** The kenneld binary's main, IPC handling, kennel registry, daemon supervision, audit reader.

**Public surface (binary).** The IPC server protocol described in `02-4-ipc.md`.

**Depends on.** `kennel-policy`, `kennel-ipc-server` (see below), `kennel-bpf` (ringbuf reader), `kennel-audit`, `kennel-spawn` (optional — when kenneld performs spawns on behalf of clients), `kennel-syscall` (for the few syscalls outside spawn).

### `kennel-ipc-shared`, `kennel-ipc-client`, `kennel-ipc-server`

**Purpose.** The wire-format types and the client/server framing logic for the protocols in `02-4-ipc.md`. Split into three crates so that:

- The CLI links only `client`; the server code is not in the CLI binary.
- kenneld links only `server`; the client code is not in the daemon binary.
- The wire types and framing live in `shared`, used by both.

**Public surface.**
- `kennel-ipc-shared`: request/response types per `02-4-ipc.md`, framing functions.
- `kennel-ipc-client`: `Client::connect(socket: &Path)`, `Client::request(req) -> Response`, streaming subscription helpers.
- `kennel-ipc-server`: `Server::bind(socket: &Path)`, `accept_loop`, request dispatcher trait that kenneld implements.

**Depends on.** `serde`, `tokio` (server only; client can be sync), `kennel-syscall` (for `SO_PEERCRED` and lockfile). Wire framing is TBD (not `serde_json`).

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
