# Crate decomposition

This chapter describes the Cargo workspace layout: which crates exist, what each owns, how they depend on each other, and what build-time choices they expose. The *public APIs* of each crate are in `02-6-internal-api.md`; this chapter is the structural view — how the code is cut up, not what each piece exposes.

> **As-built status (see `08-as-built-notes.md` §8.1).** The implemented workspace has **8** crates, not the ~13 this chapter originally drew. The separate `kennel-ipc-shared`/`-client`/`-server`, `kennel-cli`, and `kennel-audit` crates were **folded**: the control protocol lives in `kenneld::control`, the privhelper wire in `kennel-privhelper::wire`, the `kennel` CLI is a binary inside `kenneld` (`src/bin/kennel.rs`), and audit is split between the BPF ringbuf drain (`kennel-bpf`) and the netproxy's JSONL formatter. The async-runtime claims below are also stale — everything is blocking, thread-per-connection. The layout and notes below have been corrected to match.

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
├── crates/                          Rust workspace members (the 8 as-built)
│   ├── kennel-syscall/              the only unsafe-bearing crate (besides BPF FFI)
│   ├── kennel-text/                 sanitisation helpers
│   ├── kennel-policy/               TOML parsing, signature verification (settled-policy core)
│   ├── kennel-bpf/                  hand-rolled bpf(2) loader (object for ELF), .o, ringbuf reader
│   ├── kennel-spawn/                policy → Plan → setup sequence (incl. the pivot_root view) → execve
│   ├── kennel-netproxy/             binary: SOCKS5/HTTP egress proxy (blocking, thread-per-conn)
│   ├── kennel-privhelper/           binary + lib: privileged operations helper (wire format in src/wire.rs)
│   └── kenneld/                     lib + binaries: per-user supervisor (src/bin/kenneld.rs)
│                                    and the CLI (src/bin/kennel.rs); control protocol in src/control.rs
│       (folded-in, no separate crate: kennel-ipc-*, kennel-cli, kennel-audit — see §8.1)
│       (deferred: kennel-checksum-verify — shell witness exists; Rust crate at first vendored-dep, §8.2)
├── tools/
│   ├── install-hooks.sh             git hooks installer
│   ├── verify-checksums.sh          shell verifier (twin of kennel-checksum-verify)
│   ├── audit-helper/                helper for §5.5 dep audit
│   └── git-hooks/                   in-tree git hook scripts
├── fuzz/                            cargo-fuzz targets
└── architecture/, docs/, .github/, etc.
```

Every Rust crate in `crates/` is prefixed `kennel-` per CODING-STANDARDS.md §3. The binary-bearing crates are `kennel-netproxy` (`src/main.rs`), `kennel-privhelper` (`src/main.rs` + a library half for `wire`/`validate`), and `kenneld` (a library half in `src/lib.rs` providing the orchestration both binaries use, plus `src/bin/kenneld.rs` for the daemon and `src/bin/kennel.rs` for the CLI). The remaining crates are libraries (`src/lib.rs`).

---

## Dependency direction

The workspace is acyclic and layered. Lower-level crates do not depend on higher-level ones.

As-built (8 crates; the control/CLI/audit layers are folded into kenneld and the
functional crates rather than separate — see §8.1):

```
        kenneld (lib + bin kenneld + bin kennel)   kennel-netproxy (bin)
          |  owns control.rs (CLI<->daemon wire)      |
          |  + proxy.rs config writer                 |
          +----------------+--------------------------+
                           |
       +-------------+------+------+--------------+
       |             |             |              |
  kennel-spawn  kennel-privhelper  kennel-bpf   kennel-policy
       |          (lib+bin; wire.rs)   |              |
       +-------------+-------------+----+-------------+
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
- **`kennel-text` is a leaf-side utility crate** consumed by everything that emits text. It has no Project Kennel deps (only stdlib and minimal external crates). (There is no `kennel-audit` crate as-built — see §8.1; audit is split between the BPF ringbuf drain and the netproxy's formatter.)
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

### `kennel-audit` (not built as a crate — see §8.1/§8.2)

The unified audit writer + sink crate described here (and the journald/syslog/stdout sinks + feature flags) is **deferred**. As built, audit is split: BPF events are drained from a kernel ring buffer by `kennel-bpf::ringbuf` (drops on full), and the egress proxy formats one JSONL record per request in `kennel-netproxy::audit` (the server owns the sink — a per-kennel file, wired by kenneld, or stderr). When a unified writer/sink layer lands, this section becomes its home; until then see `02-3-audit-schema.md` and §8.2.

### `kennel-bpf`

- Carries `#![allow(unsafe_code)]` for the hand-rolled `bpf(2)` FFI surface (confined to `sys.rs`); same review discipline as `kennel-syscall`. ELF parsing is delegated to `object`; we do **not** use libbpf-rs/libbpf-sys or aya.
- The `bpf/` programs compile against the kernel UAPI (no CO-RE/`vmlinux.h`); `object` parses the `.o` and the loader resolves map relocations by symbol name (see `06-build-and-test.md`, `bpf/README.md`).
- The compiled `.bpf.o` files are embedded into the crate (no skeleton generation); `KENNEL_MAPS`/`KENNEL_PROGRAMS` describe the maps and programs in Rust, mirroring `bpf/maps.h`.

### IPC (folded — no `kennel-ipc-*` crates; see §8.1)

The three-crate IPC split was not built. As-built, the control protocol (CLI ↔ kenneld) lives in `kenneld::control` (`Request`/`Response` + length-prefixed `read_frame`, native-endian, `MAX_MESSAGE`-bounded) and the privhelper protocol in `kennel-privhelper::wire` (fixed-size packed structs). Both are sync/blocking; there is no async runtime anywhere. The wire parsers are the natural fuzz-target homes when the fuzzing harness lands (§8.2).

### `kennel-spawn`

- The largest crate by line count. Coordinates everything: policy validation, BPF map population, namespace setup, mount construction, Landlock sealing, seccomp installation, capability drop, environment construction, execve.
- Has a build-time feature flag `bwrap-compose` (default-off): when enabled, the namespace and mount phases are delegated to `bubblewrap` via subprocess; when disabled, the work is done in-crate via `kennel-syscall`. See `06-build-and-test.md` for the rationale.
- Has integration tests that require root (in `tests/` with a `#[cfg(feature = "root-tests")]` gate).

### `kennel-netproxy`

- Binary crate. **Sync, blocking — one thread per connection. No async runtime** (§8.1).
- The SOCKS5/HTTP server lives in `src/server.rs`; the allowlist evaluator in `src/allow.rs`; both are unit-tested without the network.

### `kennel-privhelper`

- Binary crate. Sync, no async runtime.
- `[profile.release] panic = "abort"`; `[profile.test] panic = "unwind"` per CODING-STANDARDS.md §8.5.
- Has its own dep list distinct from the workspace: only `kennel-syscall`, `kennel-text`, `serde`. Audit events are written as JSON Lines by a small hand-rolled emitter (fixed schema — no `serde_json`). No async, no proc-macros beyond serde_derive.

### `kenneld`

- Library + binaries. **Sync, blocking — `serve()` accepts and spawns one thread per connection. No async runtime** (§8.1).
- Owns the in-memory kennel registry, the per-kennel orchestration (`lib.rs`), the control protocol (`control.rs`), and the audit reader for the BPF ringbuf.

### `kennel-cli` (folded into `kenneld` as `src/bin/kennel.rs`, §8.1)

- The `kennel` binary lives inside `kenneld`, not a separate crate. It is a thin sync Unix-socket client of the control protocol in `kenneld::control`.
- Argument parsing uses `lexopt` (not `clap` — see `DEPENDENCIES.md`; `clap`'s proc-macro tree was rejected for the CLI in favour of the dependency-light `lexopt`).

### `kennel-checksum-verify` (deferred — shell twin exists, Rust crate not yet built, §8.2)

- Will be a binary crate with a tiny dep graph: `sha2`, `serde`, `toml`, and that's it.
- The shell-script twin in `tools/verify-checksums.sh` (system `sha256sum`) exists today; the Rust crate lands at/after the first vendored-dep milestone. Both must agree; CI runs both.

---

## Build-time feature flags

A small set of feature flags allows distribution variation without forking. Each flag is documented at the use site and listed here.

| Flag | Crate | Default | Effect |
|---|---|---|---|
| `bpf-egress` | `kennel-privhelper` | off | Compile the BPF load/attach path into the privhelper (clang-free, embedded `.o`). Required for live egress; rebuild before root tests (§8.4). |
| `root-tests` | several | off | Compile and run tests that require root (cgroup creation, namespace ops, Landlock sealing, the kenneld e2e). |
| `sink-*` | (`kennel-audit`, deferred) | — | The audit sink flags (`sink-file`/`-journald`/`-syslog`/`-stdout`) belong to the not-yet-built audit crate (§8.2). |

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

- **A new sink** for the audit stream → today, where the audit is produced (the netproxy's `audit.rs`, or the BPF ringbuf reader in kenneld); a unified audit crate with sink feature flags is the deferred home (§8.2).
- **A new BPF program** → C source in `bpf/`, loader code in `kennel-bpf`. No new crate.
- **A new privileged operation** → a new operation type in `kennel-privhelper`. No new crate; the privhelper's scope is bounded by its review burden, not by line count.
- **A new external integration** (e.g., an MCP server to expose audit events via MCP) → a separate binary crate `kennel-<integration>`. Adding such an integration is itself an architectural decision and needs a doc update.

---

## What this chapter does not cover

- Per-crate public APIs and trait surfaces: `02-6-internal-api.md`.
- Build commands, CI matrix, test taxonomy: `06-build-and-test.md`.
- Dependency-policy rules (when to add a dep, audit cadence): CODING-STANDARDS.md §5.
- Specific dependency versions: `Cargo.toml` and `CHECKSUMS.toml`.
- Workspace boundaries vs published crates: nothing is currently published to crates.io; the workspace is internal.
