# Crate decomposition

This chapter describes the Cargo workspace layout: which crates exist, what each owns, how they depend on each other, and what build-time choices they expose. The *public APIs* of each crate are in `02-6-internal-api.md`; this chapter is the structural view — how the code is cut up, not what each piece exposes.

The workspace has **10 crates**: `kennel-policy`, `kennel-syscall`, `kennel-bpf`, `kennel-spawn`, `kennel-netproxy`, `kennel-privhelper`, `kenneld`, `kennel-text`, `kennel-ssh-reorigin`, and `kennel-socks-connect`. The last two are standalone, std-only SSH helpers (`07-8-ssh.md` §7.8.4) that depend on no other Project Kennel crate by design — they must stay minimal and self-contained: `kennel-ssh-reorigin` is the bastion's re-origination forced command, and `kennel-socks-connect` is the `ssh` `ProxyCommand` that SOCKS5s through the egress proxy to reach the bastion. IPC, the CLI, and audit are folded rather than carved into their own crates: the control protocol lives in `kenneld::control`, the privhelper wire in `kennel-privhelper::wire`, the `kennel` CLI is a binary inside `kenneld` (`src/bin/kennel.rs`), and audit is split between the BPF ringbuf drain (`kennel-bpf`) and the netproxy's JSONL formatter (`kennel-netproxy::audit`). The crate count is kept small deliberately — a wire protocol shared by exactly two binaries is a module in one of them, not a third crate, and the CLI and daemon ship from the same crate so their protocol cannot drift. The whole workspace is blocking, thread-per-connection; no async runtime is linked.

---

## Workspace layout

```
kennel/
├── Cargo.toml                       workspace root, [workspace] section, shared profile
├── Cargo.lock
├── rust-toolchain.toml
├── CHECKSUMS.toml
├── src/vendor/                  vendored .crate tarballs (§5.5 CODING-STANDARDS)
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
├── crates/                          Rust workspace members (10)
│   ├── kennel-syscall/              the only unsafe-bearing crate (besides BPF FFI)
│   ├── kennel-text/                 sanitisation helpers
│   ├── kennel-policy/               TOML parsing, signature verification (settled-policy core)
│   ├── kennel-bpf/                  hand-rolled bpf(2) loader (object for ELF), .o, ringbuf reader
│   ├── kennel-spawn/                policy → Plan → setup sequence (incl. the pivot_root view) → execve
│   ├── kennel-netproxy/             binary + lib: SOCKS5/HTTP egress proxy (blocking, thread-per-conn)
│   ├── kennel-privhelper/           binary + lib: privileged operations helper (wire format in src/wire.rs)
│   ├── kennel-ssh-reorigin/         binary + lib: SSH re-origination forced command (std-only; §7.8.4)
│   ├── kennel-socks-connect/        binary + lib: SOCKS5 stdio connector for ssh ProxyCommand (std-only; §7.8.4)
│   └── kenneld/                     lib + binaries: per-user supervisor (src/bin/kenneld.rs), CLI (kennel.rs), bastion AKC (kennel-akc.rs)
│                                    and the CLI (src/bin/kennel.rs); control protocol in src/control.rs
│       (folded in, no separate crate: IPC → kenneld::control + kennel-privhelper::wire;
│        CLI → kenneld/src/bin/kennel.rs; audit → kennel-bpf ringbuf + kennel-netproxy::audit)
├── tools/
│   ├── install-hooks.sh             git hooks installer
│   ├── verify-checksums.sh          shell checksum-manifest verifier
│   ├── audit-helper/                helper for §5.5 dep audit
│   └── git-hooks/                   in-tree git hook scripts
├── fuzz/                            cargo-fuzz targets
└── architecture/, docs/, .github/, etc.
```

Every Rust crate in `crates/` is prefixed `kennel-` per CODING-STANDARDS.md §3. The binary-bearing crates are `kennel-netproxy` (`src/main.rs`), `kennel-privhelper` (`src/main.rs` + a library half for `wire`/`validate`), `kennel-ssh-reorigin` (`src/main.rs` + a library half holding the tested re-origination core), `kennel-socks-connect` (`src/main.rs` + a library half holding the tested SOCKS5 wire codec), and `kenneld` (a library half in `src/lib.rs` providing the orchestration its binaries share, plus `src/bin/kenneld.rs` for the daemon, `src/bin/kennel.rs` for the CLI, and `src/bin/kennel-akc.rs` for the SSH bastion's root-owned `AuthorizedKeysCommand`, which reuses `kenneld::control` to query the daemon — §7.8.7). The remaining crates are libraries (`src/lib.rs`).

---

## Dependency direction

The workspace is acyclic and layered. Lower-level crates do not depend on higher-level ones. The control, CLI, and audit layers are folded into kenneld and the functional crates rather than carved out separately:

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

  kennel-ssh-reorigin (bin)   ← stands alone: std-only, no Project Kennel deps.
                                The bastion's forced command must stay minimal
                                and self-contained (§7.8.4).
  kennel-socks-connect (bin)  ← stands alone: std-only. The ssh ProxyCommand that
                                SOCKS5s through the egress proxy to the bastion.
```

Rules:

- **No cycles.** Enforced by Cargo (a cycle is a build error).
- **No depth skipping in spirit.** A crate may depend on any layer below it, but a binary depending directly on `kennel-syscall` to bypass the safe wrappers in `kennel-spawn` is a smell that warrants a review note.
- **`kennel-syscall` is the only `unsafe`-bearing crate** (besides `kennel-bpf` for its hand-rolled `bpf(2)` FFI surface). Every other crate carries `#![forbid(unsafe_code)]` per CODING-STANDARDS.md §4.
- **`kennel-text` is a leaf-side utility crate** consumed by everything that emits text. It has no Project Kennel deps (only stdlib and minimal external crates). `kennel-audit` builds on it for the single sanitisation pass.
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

### Audit (`kennel-audit`)

`kennel-audit` (`#![forbid(unsafe_code)]`) is the unified writer: the canonical `AuditEvent`, one `kennel-text` sanitisation pass, per-class level filtering, and a `Sink` trait fanning each event out to the file, stdout, syslog, and (feature `audit-journald`) journald sinks. The journald sink and the UUIDv7's randomness are the only parts needing FFI/`unsafe`; they live in `kennel-syscall` (`journal`, `random`). kenneld builds the writer from the settled `AuditRuntime` and emits lifecycle events through it; see `02-3-audit-schema.md` for the schema. Not yet routed through the writer: the BPF events (still drained from the kernel ring buffer by `kennel-bpf::ringbuf`, drops on full) and the egress proxy's per-request records (`kennel-netproxy::audit`, schema-forward-compatible) — a roadmap remnant.

### `kennel-bpf`

- Carries `#![allow(unsafe_code)]` for the hand-rolled `bpf(2)` FFI surface (confined to `sys.rs`); same review discipline as `kennel-syscall`. ELF parsing is delegated to `object`; we do **not** use libbpf-rs/libbpf-sys or aya.
- The `bpf/` programs compile against the kernel UAPI (no CO-RE/`vmlinux.h`); `object` parses the `.o` and the loader resolves map relocations by symbol name (see `06-build-and-test.md`, `bpf/README.md`).
- The compiled `.bpf.o` files are embedded into the crate (no skeleton generation); `KENNEL_MAPS`/`KENNEL_PROGRAMS` describe the maps and programs in Rust, mirroring `bpf/maps.h`.

### IPC (folded — no `kennel-ipc-*` crates)

The control protocol (CLI ↔ kenneld) lives in `kenneld::control` (`Request`/`Response` + length-prefixed `read_frame`, native-endian, `MAX_MESSAGE`-bounded) and the privhelper protocol in `kennel-privhelper::wire` (fixed-size packed structs). Each protocol is shared by exactly two binaries that ship from the same crate, so it is a module there rather than a standalone crate. Both are sync/blocking; there is no async runtime anywhere. The wire parsers are the natural fuzz-target homes.

### `kennel-spawn`

- The largest crate by line count. Coordinates everything: policy validation, BPF map population, namespace setup, mount construction, Landlock sealing, seccomp installation, capability drop, environment construction, execve.
- Has a build-time feature flag `bwrap-compose` (default-off): when enabled, the namespace and mount phases are delegated to `bubblewrap` via subprocess; when disabled, the work is done in-crate via `kennel-syscall`. See `06-build-and-test.md` for the rationale.
- Has integration tests that require root (in `tests/` with a `#[cfg(feature = "root-tests")]` gate).

### `kennel-netproxy`

- Binary crate with a library half. **Sync, blocking — one thread per connection. No async runtime.**
- The SOCKS5/HTTP server lives in `src/server.rs` (`socks5.rs`/`http.rs`); the allowlist evaluator in `src/allow.rs`; the JSONL audit formatter in `src/audit.rs`. All are unit-tested without the network.

### `kennel-privhelper`

- Binary crate. Sync, no async runtime.
- `[profile.release] panic = "abort"`; `[profile.test] panic = "unwind"` per CODING-STANDARDS.md §8.5.
- Has its own dep list distinct from the workspace: only `kennel-syscall`, `kennel-text`, `serde`. Audit events are written as JSON Lines by a small hand-rolled emitter (fixed schema — no `serde_json`). No async, no proc-macros beyond serde_derive.

### `kennel-ssh-reorigin`

- Binary crate with a library half; **std-only, no Project Kennel deps and no external crates** — the SSH bastion's forced command must stay minimal and auditable (`07-8-ssh.md` §7.8.4).
- The library (`src/lib.rs`) holds the security-load-bearing core, all pure and unit-tested: strict `--dest`/`--key` parsing (option-injection-proof), the hostname and `SHA256:` grammars, `$SSH_USER_AUTH` publickey confirmation (fail-closed), exact fingerprint→agent-identity selection, and outbound-`ssh` argv construction (`--`-terminated so the attacker-controlled `$SSH_ORIGINAL_COMMAND` can never be read as a flag). `main.rs` is the thin IO tail (`ssh-add` enumeration, identity-file write, `execvp ssh`).
- Carries no key material: only the *public* half of the selected key is written (to a `0600` temp file), the private key stays in the user's agent/token.

### `kennel-socks-connect`

- Binary crate with a library half; **std-only, no Project Kennel deps and no external crates**. The `ssh` `ProxyCommand` a confined kennel uses to reach the bastion: a kennel can `connect()` only to its egress proxy (§7.3.2), and `ssh` has no built-in SOCKS client, so this speaks SOCKS5 CONNECT to `$KENNEL_SOCKS_PROXY` and splices stdio to the stream — without depending on `nc`/`ncat` being present in the workload image.
- The library (`src/lib.rs`) holds the pure SOCKS5 wire codec (greeting, CONNECT request for IPv4/IPv6/domain, reply parsing), unit-tested. `main.rs` does the TCP + bidirectional splice; the downlink flushes per chunk (stdout is a `LineWriter` and SSH key-exchange carries no newlines — left buffered it would stall the handshake).

### `kenneld`

- Library + binaries. **Sync, blocking — `serve()` accepts and spawns one thread per connection. No async runtime.**
- Owns the in-memory kennel registry, the per-kennel orchestration (`lib.rs`), the control protocol (`control.rs`), the synthetic `/etc` (`etc.rs`) and synthetic `~/.ssh` (`ssh.rs`) generators, and the audit reader for the BPF ringbuf.

### CLI (folded into `kenneld` as `src/bin/kennel.rs`)

- The `kennel` binary lives inside `kenneld`, not a separate crate. It is a thin sync Unix-socket client of the control protocol in `kenneld::control`. Shipping the CLI and the daemon from one crate keeps the protocol from drifting between them.
- Argument parsing is hand-rolled over `std::env::args` (dispatch on the first argument, each subcommand parsing its own flags); no `clap` and no proc-macro arg-parser is linked.

### Checksum verification (shell witness; no Rust crate)

- The checksum-manifest verifier is the shell script `tools/verify-checksums.sh` (system `sha256sum`). A Rust twin (with a tiny `sha2`/`serde`/`toml` dep graph) is a roadmap item; when it lands, both must agree and CI runs both.

---

## Build-time feature flags

A small set of feature flags allows distribution variation without forking. Each flag is documented at the use site and listed here.

| Flag | Crate | Default | Effect |
|---|---|---|---|
| `bpf-egress` | `kennel-privhelper` | off | Compile the BPF load/attach path into the privhelper (clang-free, embedded `.o`). Required for live egress; rebuild before root tests (`06-build-and-test.md`). |
| `root-tests` | several | off | Compile and run tests that require root (cgroup creation, namespace ops, Landlock sealing, the kenneld e2e). |

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

- **A new sink** for the audit stream → `kennel-audit` (implement the `Sink` trait; gate any new system-library link behind a feature, as `audit-journald` does).
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
