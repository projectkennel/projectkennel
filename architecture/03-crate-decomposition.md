# Crate decomposition

This chapter describes the Cargo workspace layout: which crates exist, what each owns, how they depend on each other, and what build-time choices they expose. The *public APIs* of each crate are in `02-6-internal-api.md`; this chapter is the structural view — how the code is cut up, not what each piece exposes.

---

## Workspace layout

```
kennel/
├── Cargo.toml                       workspace root, [workspace] section, shared profile
├── Cargo.lock
├── rust-toolchain.toml
├── CHECKSUMS.toml
├── crates-archive/                  vendored .crate tarballs (§5.5 CODING-STANDARDS)
├── bpf/                             BPF C source
│   ├── connect4.bpf.c
│   ├── connect6.bpf.c
│   ├── bind4.bpf.c
│   ├── bind6.bpf.c
│   ├── setsockopt.bpf.c
│   ├── sock_create.bpf.c
│   ├── sendmsg4.bpf.c
│   ├── sendmsg6.bpf.c
│   ├── maps.h                       single source of truth for map layouts
│   ├── audit_events.h               ringbuf event struct declarations
│   ├── kennel.bpf.h                 shared helpers (UAPI-based; no vmlinux.h/CO-RE)
│   ├── README.md                    why no CO-RE; build/inspect instructions
│   └── HELPERS.md                   whitelist of permitted BPF helper functions
├── crates/                          Rust workspace members
│   ├── kennel-syscall/              the only unsafe-bearing crate (besides BPF FFI)
│   ├── kennel-text/                 sanitisation helpers
│   ├── kennel-policy/               TOML parsing, template resolution, signature verification
│   ├── kennel-audit/                event types, writer, sink implementations
│   ├── kennel-bpf/                  hand-rolled bpf(2) loader (object for ELF), .o, ringbuf reader
│   ├── kennel-ipc-shared/           wire-format types, framing
│   ├── kennel-ipc-client/           client-side connection, request, subscribe
│   ├── kennel-ipc-server/           server-side accept loop, dispatcher trait
│   ├── kennel-spawn/                policy → setup sequence → execve
│   ├── kennel-netproxy/             binary: SOCKS5 proxy
│   ├── kennel-privhelper/           binary: privileged operations helper
│   ├── kenneld/                     binary: per-user supervisor
│   ├── kennel-cli/                  binary: kennel(1)
│   └── kennel-checksum-verify/      binary: tools/verify-checksums
├── tools/
│   ├── install-hooks.sh             git hooks installer
│   ├── verify-checksums.sh          shell verifier (twin of kennel-checksum-verify)
│   ├── audit-helper/                helper for §5.5 dep audit
│   └── git-hooks/                   in-tree git hook scripts
├── fuzz/                            cargo-fuzz targets
└── architecture/, docs/, .github/, etc.
```

Every Rust crate in `crates/` is prefixed `kennel-` per CODING-STANDARDS.md §3. Binary crates (`kennel-netproxy`, `kennel-privhelper`, `kenneld`, `kennel-cli`, `kennel-checksum-verify`) have a `src/main.rs`; library crates have `src/lib.rs`. Some binaries also expose a tiny library half (`kenneld` exposes its dispatcher trait via `kennel-ipc-server`; the binary's own code is `main.rs` only).

---

## Dependency direction

The workspace is acyclic and layered. Lower-level crates do not depend on higher-level ones.

```
                      kennel-cli           kenneld
                          |                   |
                          +---------+---------+
                                    |
                          kennel-ipc-client / server
                                    |
                          kennel-ipc-shared
                                    |
       +-------------+-------------+-------------+
       |             |             |             |
  kennel-spawn  kennel-netproxy  kennel-bpf   kennel-policy
       |             |             |             |
       +-------------+-------------+-------------+
                          |
                    kennel-audit
                          |
                    kennel-text
                          |
                    kennel-syscall
                          |
                 (libc, nix; kennel-bpf adds object)
```

Rules:

- **No cycles.** Enforced by Cargo (a cycle is a build error).
- **No depth skipping in spirit.** A crate may depend on any layer below it, but a binary depending directly on `kennel-syscall` to bypass the safe wrappers in `kennel-spawn` is a smell that warrants a review note.
- **`kennel-syscall` is the only `unsafe`-bearing crate** (besides `kennel-bpf` for its hand-rolled `bpf(2)` FFI surface). Every other crate carries `#![forbid(unsafe_code)]` per CODING-STANDARDS.md §4.
- **`kennel-text` and `kennel-audit` are leaf-side utility crates** consumed by everything that emits text or events. They have no Project Kennel deps (only stdlib and minimal external crates).
- **`kennel-policy`** does not depend on `kennel-spawn`, `kennel-bpf`, or any binary crate. The policy module is purely functional: same input, same output, no runtime side-effects.

---

## Per-crate notes

The full public-API description for each crate lives in `02-6-internal-api.md`. This section adds the structural and build-side notes that do not belong with the API description.

### `kennel-syscall`

- **Size ceiling: 1500 lines of Rust.** Reviewable in one sitting per CODING-STANDARDS.md §4.
- Carries `#![allow(unsafe_code)]` (the only library crate that does, alongside `kennel-bpf`).
- Listed in `UNSAFE-CRATES.md` at the workspace root.
- Per-feature `cfg`s for kernel-version conditional code paths; documented as the only crate where this is acceptable.

### `kennel-text`

- Tiny crate, ~200 lines target.
- Has its own fuzz target under `fuzz/text/`.

### `kennel-policy`

- Largest non-binary crate. Owns the schema types and the resolver.
- Builds with no I/O (file reading is the caller's responsibility); takes `&[u8]` for parsing.
- Has fuzz targets for the parser and the resolver.

### `kennel-audit`

- Owns the `AuditEvent` enum and `AuditWriter`.
- Sink implementations are behind feature flags:
  - `sink-file` (default-on): JSONL file writer.
  - `sink-journald` (default-off): links a vetted Rust journald binding.
  - `sink-syslog` (default-off): `/dev/log` writer; no external dep beyond stdlib.
  - `sink-stdout` (default-on): emits to a `Write` handle the caller provides.
- The default feature set is `["sink-file", "sink-stdout"]`. Distributions with journald enable `sink-journald` in their build.

### `kennel-bpf`

- Carries `#![allow(unsafe_code)]` for the hand-rolled `bpf(2)` FFI surface (confined to `sys.rs`); same review discipline as `kennel-syscall`. ELF parsing is delegated to `object`; we do **not** use libbpf-rs/libbpf-sys or aya.
- The `bpf/` programs compile against the kernel UAPI (no CO-RE/`vmlinux.h`); `object` parses the `.o` and the loader resolves map relocations by symbol name (see `06-build-and-test.md`, `bpf/README.md`).
- The compiled `.bpf.o` files are embedded into the crate (no skeleton generation); `KENNEL_MAPS`/`KENNEL_PROGRAMS` describe the maps and programs in Rust, mirroring `bpf/maps.h`.

### `kennel-ipc-shared`, `-client`, `-server`

- The three-crate split keeps the CLI binary free of server code and kenneld free of client code (a small but real attack-surface reduction).
- `kennel-ipc-shared` is sync-only (no async runtime). `kennel-ipc-client` is sync. `kennel-ipc-server` uses the workspace's async runtime (`tokio`).
- The wire-format types in `kennel-ipc-shared` are tested via fuzz targets at the framing layer.

### `kennel-spawn`

- The largest crate by line count. Coordinates everything: policy validation, BPF map population, namespace setup, mount construction, Landlock sealing, seccomp installation, capability drop, environment construction, execve.
- Has a build-time feature flag `bwrap-compose` (default-off): when enabled, the namespace and mount phases are delegated to `bubblewrap` via subprocess; when disabled, the work is done in-crate via `kennel-syscall`. See `06-build-and-test.md` for the rationale.
- Has integration tests that require root (in `tests/` with a `#[cfg(feature = "root-tests")]` gate).

### `kennel-netproxy`

- Binary crate. Uses the async runtime.
- The SOCKS5 server lives in `src/server.rs`; the allowlist evaluator in `src/allow.rs`; both are unit-tested without the network.

### `kennel-privhelper`

- Binary crate. Sync, no async runtime.
- `[profile.release] panic = "abort"`; `[profile.test] panic = "unwind"` per CODING-STANDARDS.md §8.5.
- Has its own dep list distinct from the workspace: only `kennel-syscall`, `kennel-text`, `serde`, `serde_json`. No async, no proc-macros beyond serde_derive.

### `kenneld`

- Binary crate. Uses the async runtime.
- Owns the in-memory kennel registry, the per-kennel state machines, the audit reader for the BPF ringbuf.

### `kennel-cli`

- Binary crate. Mostly sync; uses `kennel-ipc-client` sync mode.
- The subcommand dispatcher uses `clap` derive. Per CODING-STANDARDS.md §5.3, `clap`'s proc-macros require explicit per-version justification in `DEPENDENCIES.md`; we accept them as the alternative (hand-written argument parsing across 13 subcommands) is worse.

### `kennel-checksum-verify`

- Binary crate. Tiny dep graph: `sha2`, `serde`, `toml`, and that's it.
- The shell-script twin in `tools/verify-checksums.sh` uses system `sha256sum`. Both must agree; CI runs both.

---

## Build-time feature flags

A small set of feature flags allows distribution variation without forking. Each flag is documented at the use site and listed here.

| Flag | Crate | Default | Effect |
|---|---|---|---|
| `bwrap-compose` | `kennel-spawn` | off | Delegate namespace/mount setup to `bubblewrap` subprocess instead of doing it in-crate. |
| `sink-file` | `kennel-audit` | on | Compile the JSONL file sink. |
| `sink-journald` | `kennel-audit` | off | Compile the systemd-journald sink. Pulls a vetted journald binding crate. |
| `sink-syslog` | `kennel-audit` | off | Compile the syslog sink. |
| `sink-stdout` | `kennel-audit` | on | Compile the stdout sink. |
| `root-tests` | several | off | Compile and run tests that require root (cgroup creation, namespace ops, Landlock sealing on real kernel). |

Feature combinations tested in CI are listed in `06-build-and-test.md`. The default feature set is the minimum that produces a working binary for the most-common installation (single-user developer workstation, no journald requirement).

---

## Workspace `Cargo.toml`

The root `Cargo.toml` carries:

- `[workspace]` section listing every crate in `crates/`.
- `[workspace.package]` shared metadata: `rust-version`, `edition`, `license`, `authors`.
- `[workspace.dependencies]` for every external crate. Member crates reference these by `dep = { workspace = true }` rather than redeclaring versions, so a version bump touches one place.
- `[profile.release]`: `lto = "thin"`, `opt-level = 3`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`. The `panic = "abort"` is workspace-wide for release builds; the test profile retains unwinding (CODING-STANDARDS.md §8.5).
- `[profile.release-with-debuginfo]`: a custom profile inheriting from `release` with `debug = true`, used for the binaries that ship with separate `.debug` files.

---

## Where to add new crates

- **A new sink** for the audit stream → a feature flag in `kennel-audit`, not a new crate. The sink is small enough that a separate crate adds overhead without benefit.
- **A new BPF program** → C source in `bpf/`, loader code in `kennel-bpf`. No new crate.
- **A new privileged operation** → a new operation type in `kennel-privhelper`. No new crate; the privhelper's scope is bounded by its review burden, not by line count.
- **A new external integration** (e.g., an MCP server to expose audit events via MCP) → consider a separate binary crate `kennel-<integration>`, depending on `kennel-audit` and the integration's protocol. Adding such an integration is itself an architectural decision and needs a doc update.

---

## What this chapter does not cover

- Per-crate public APIs and trait surfaces: `02-6-internal-api.md`.
- Build commands, CI matrix, test taxonomy: `06-build-and-test.md`.
- Dependency-policy rules (when to add a dep, audit cadence): CODING-STANDARDS.md §5.
- Specific dependency versions: `Cargo.toml` and `CHECKSUMS.toml`.
- Workspace boundaries vs published crates: nothing is currently published to crates.io; the workspace is internal.
